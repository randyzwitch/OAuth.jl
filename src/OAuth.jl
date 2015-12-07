module OAuth

using Compat
using URIParser, Requests, Nettle

export
oauth_timestamp,
oauth_nonce,
oauth_sign_hmac_sha1,
oauth_signing_key,
oauth_signature_base_string,
oauth_percent_encode_keys!,
oauth_serialize_url_parameters,
encodeURI!,
oauth_body_hash_file,
oauth_body_hash_data,
oauth_body_hash_encode,
oauth_header,
oauth_request_resource


#############################################################
#
# OAuth Client Functions
#
#############################################################

#Get current timestamp
function oauth_timestamp()
    "$(@compat round(Int, time()))"
end

#Generate random string
function oauth_nonce(length::Int64)
    randstring(length)
end

#HMAC-SHA1 sign message
function oauth_sign_hmac_sha1(message::AbstractString,signingkey::AbstractString)
    base64encode(digest("sha1", signingkey, message))
end

#Create signing key
function oauth_signing_key(oauth_consumer_secret::AbstractString, oauth_token_secret::AbstractString)
    "$(oauth_consumer_secret)&$(oauth_token_secret)"
end

#Create signature_base_string
function oauth_signature_base_string(httpmethod::AbstractString, url::AbstractString, parameterstring::AbstractString)
    "$(httpmethod)&$(encodeURI(url))&$(encodeURI(parameterstring))"
end

#URL-escape keys
function oauth_percent_encode_keys!(options::Dict)
    #options encoded
    originalkeys = collect(keys(options))

    for key in originalkeys
        key_str = string(key)
        encoded_key = encodeURI(key_str)

        options[encoded_key] = encodeURI(options[key_str])
        if encodeURI(key_str) != key
            delete!(options, key_str)
        end
    end

    options
end

@deprecate(
    oauth_percent_encode_keys(options::Dict),
    oauth_percent_encode_keys!(options::Dict)
)

#Create query string from dictionary keys
oauth_serialize_url_parameters(options::Dict) = join(
    ["$key=$(options[key])" for key in sort!(collect(keys(options)))],
    "&"
)

# See: https://github.com/randyzwitch/OAuth.jl/issues/3
encodeURI(s) = URIParser.escape(s)

function encodeURI!(dict_of_parameters::Dict)
    for (k, v) in dict_of_parameters
        if typeof(v) <: AbstractString
            dict_of_parameters[k] = encodeURI(v)
        end
    end
    return dict_of_parameters
end

@deprecate(
    encodeURI(dict_of_parameters::Dict),
    encodeURI!(dict_of_parameters::Dict)
)

function oauth_body_hash_file(filename::AbstractString)
    oauth_body_hash_data(readall(open(filename)))
end

function oauth_body_hash_data(data::AbstractString)
    "oauth_body_hash=$(oauth_body_hash_encode(data))"
end

function oauth_body_hash_encode(data::AbstractString)
        base64encode(digest("SHA1", data))
end

#Use this function to build the header for every OAuth call
# This function assumes that options Dict has already been run through encodeURI!
function oauth_header(httpmethod, baseurl, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret;
                     oauth_signature_method = "HMAC-SHA1",
                     oauth_version = "1.0")

    #keys for parameter string
    options["oauth_consumer_key"] = oauth_consumer_key
    options["oauth_nonce"] = oauth_nonce(32)
    options["oauth_signature_method"] = oauth_signature_method
    options["oauth_timestamp"] = oauth_timestamp()
    options["oauth_token"] = oauth_token
    options["oauth_version"] = oauth_version

    #options encoded
    oauth_percent_encode_keys!(options)

    #Create ordered query string
    parameterstring = oauth_serialize_url_parameters(options)

    #Calculate signature_base_string
    signature_base_string = oauth_signature_base_string(uppercase(httpmethod), baseurl, parameterstring)

    #Calculate signing_key
    signing_key = oauth_signing_key(oauth_consumer_secret, oauth_token_secret)

    #Calculate oauth_signature
    oauth_sig = encodeURI(oauth_sign_hmac_sha1(signature_base_string, signing_key))

    return "OAuth oauth_consumer_key=\"$(options["oauth_consumer_key"])\", oauth_nonce=\"$(options["oauth_nonce"])\", oauth_signature=\"$(oauth_sig)\", oauth_signature_method=\"$(options["oauth_signature_method"])\", oauth_timestamp=\"$(options["oauth_timestamp"])\", oauth_token=\"$(options["oauth_token"])\", oauth_version=\"$(options["oauth_version"])\""

end

function oauth_request_resource(endpoint::AbstractString, httpmethod::AbstractString, options::Dict, oauth_consumer_key::AbstractString, oauth_consumer_secret::AbstractString, oauth_token::AbstractString, oauth_token_secret::AbstractString)
    #Build query string
    query_str = Requests.format_query_str(options)

    #Build oauth_header
    oauth_header_val = oauth_header(httpmethod, endpoint, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret)

    #Make request
    headers = @compat(
        Dict{AbstractString,AbstractString}(
            "Content-Type" => "application/x-www-form-urlencoded",
            "Authorization" => oauth_header_val,
            "Accept" => "*/*"
        )
    )

    if uppercase(httpmethod) == "POST"
        return Requests.post(URI(endpoint), query_str; headers = headers)
    elseif uppercase(httpmethod) == "GET"
        return Requests.get(URI("$(endpoint)?$query_str"); headers = headers)
    end
end

end
