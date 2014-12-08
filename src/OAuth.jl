#Wrapper around liboauth POSIX-c functions implementing the OAuth Core RFC 5849 standard
#http://liboauth.sourceforge.net/index.html

module OAuth
using Nettle, HttpCommon


########################################################################################
#
#
#   Exports & Constants
#
#
########################################################################################

export 
oauth_gen_nonce,
oauth_sign_hmac_sha1,
#oauth_sign_plaintext,
#oauth_sign_rsa_sha1,
#oauth_verify_rsa_sha1,
#oauth_split_url_parameters,
#oauth_split_post_parameters,
oauth_serialize_url,
#oauth_serialize_url_sep, - delete
#oauth_serialize_url_parameters, - delete, repetitive
#oauth_cmpstringp,




#oauth_param_exists,
#oauth_add_param_to_array,
oauth_time_independent_equals,
#oauth_sign_url2,
#oauth_sign_array2_process,
#oauth_sign_array2,
oauth_body_hash_file,
oauth_body_hash_data,
#oauth_body_hash_encode,
#oauth_sign_xmpp,
oauth_encode_base64,
oauth_decode_base64,
oauth_url_escape,
oauth_url_unescape,
#oauth_catenc,
OA_HMAC,
OA_RSA,
OA_PLAINTEXT,
OAuthMethod, #Only exporting this during development
LIBOAUTH #Only exporting this during development

# begin enum OAuthMethod
typealias OAuthMethod Uint32
const OA_HMAC = (uint32)(0)
const OA_RSA = (uint32)(1)
const OA_PLAINTEXT = (uint32)(2)
# end enum OAuthMethod



#TODO: Make this generic for all operating systems
#Do we need to use Homebrew or BinDeps to install liboauth for people or assume they installed themselves?
#const LIBOAUTH = "/usr/local/lib/liboauth.dylib"

#Stolen from Jacob ODBC.jl
let
    global LIBOAUTH
    succeeded = false
    if !isdefined(:LIBOAUTH)
        @linux_only   lib_choices = ["liboauth", "liboauth.so"]
        @windows_only lib_choices = [""]
        @osx_only     lib_choices = ["liboauth.dylib"]
        local lib
        for lib in lib_choices 
            try
                dlopen(lib)
                succeeded = true
                break
            end
        end
        succeeded || error("liboauth library not found")
        @eval const LIBOAUTH = $lib
    end
end

#TODO: errors kill kernel, so do proper error checking for each type of function

########################################################################################
#
#
#   Functions
#
#
########################################################################################

#Returns random string - Pure Julia
function oauth_gen_nonce()
	
	return randstring(32)

end

#Returns base64 string - Julia, calls Nettle
function oauth_sign_hmac_sha1(message::String,signingkey::String)

	h = HMACState(SHA1, signingkey)
	update!(h, message)
	return base64(digest!(h))

end

#Unclear the value of this function - Pure Julia
function oauth_sign_plaintext(message::String,key::String)

	error("Not Currently Implemented")

end

#Returns base64 encoded string - Pure Julia
function oauth_encode_base64(source::String)

	return base64(source)

end

#Fails test: "liboauth/OpenSSL: can not read private key"
#function oauth_sign_rsa_sha1(message::String,key::String)
#    result = ccall((:oauth_sign_rsa_sha1,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),message,key)
#    if result == C_NULL
#        error("oauth_sign_rsa_sha1 failed")
#    end
#    return bytestring(result)
#end

#Only modified argument names & types
#Cant read in private keys, so can't test
#function oauth_verify_rsa_sha1(message::String,certificate::String,signature::String)
#    result = ccall((:oauth_verify_rsa_sha1,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),message,certificate,signature)
#    if result == C_NULL
#        error("oauth_verify_rsa_sha1 failed")
#    end
#    return result
#end

#Returns url escaped string - Julia, HttpCommon
function oauth_url_escape(url::String)
    
    return encodeURI(url)

end

#Parse encoded string back to unescaped version.
function oauth_url_unescape(url::String)

    return decodeURI(url)

end

#Splits query string into components
#Answer taken from https://groups.google.com/d/msg/julia-users/BvXn7784IGw/4wO4udHnwuAJ
#function oauth_split_url_parameters(url::String)
#    
#    a = Array(Ptr{Ptr{Uint8}},1)
#    result = ccall((:oauth_split_url_parameters,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Ptr{Ptr{Uint8}}}),convert(Ptr{Uint8},url),a)
#    if result == C_NULL
#        error("oauth_split_url_parameters failed")
#    end
#    formatted_result = []
#    for i in 1:result
#        aa = unsafe_load(a[1], i)
#        push!(formatted_result, bytestring(aa))
#    end

#   #Need to free memory here
#    #https://groups.google.com/d/msg/julia-users/BvXn7784IGw/c-zND8cukp8J
#    #Not sure this is actually freeing the memory
#    ccall((:oauth_free_array,LIBOAUTH), Void, (Ptr{Cint}, Ptr{Ptr{Ptr{Uint8}}}), [result], a)
#    return formatted_result
#end

#Splits query string into components
#function oauth_split_post_parameters(url::String,usequeryescape::Bool)
#    a = Array(Ptr{Ptr{Uint8}},1)   
#    result = ccall((:oauth_split_post_paramters,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Ptr{Ptr{Uint8}}},Int16),url,a,int(usequeryescape))
#    if result == C_NULL
#        error("oauth_split_post_paramters failed")
#    end
#    formatted_result = []
#    for i in 1:result
#        aa = unsafe_load(a[1], i)
#        push!(formatted_result, bytestring(aa))
#    end
#
#    #Need to free memory here
#    #https://groups.google.com/d/msg/julia-users/BvXn7784IGw/c-zND8cukp8J
#    #Not sure this is actually freeing the memory
#    ccall((:oauth_free_array,LIBOAUTH), Void, (Ptr{Cint}, Ptr{Ptr{Ptr{Uint8}}}), [result], a)
#    return formatted_result
#end

#Feels like should also write a Dict method, which seems more natural to me - Pure Julia
#Merges/replaces oauth_serialize_url_sep
#Filters array based on 
#mod - bitwise modifiers: 1: skip all values that start with "oauth_" 2: skip all values that don't start with "oauth_" 4: double quotation marks are added around values (use with sep ", " for HTTP Authorization header).

function oauth_serialize_url(params::Array; start=1, sep='&', mod=1)

	if mod == 1
	    serialized = ""
	    for element in params[start:end]
	        serialized *= "$(element)&"
	    end
	    return chop(serialized)
	end
	elseif mod == 2
		error("Not implemented yet")
	end
	elseif mod == 4
		error("Not implemented yet")
	end
    
end

#Takes array, concatenates together based on sep
#Filters array based on 
#mod - bitwise modifiers: 1: skip all values that start with "oauth_" 2: skip all values that don't start with "oauth_" 4: double quotation marks are added around values (use with sep ", " for HTTP Authorization header).
#function oauth_serialize_url_sep(params::Array,sep::String,start::Integer, mod::Integer)
#    #argc = length(params)
#    result = ccall((:oauth_serialize_url_sep,LIBOAUTH),Ptr{Uint8},(Cint,Cint,Ptr{Ptr{Uint8}},Ptr{Uint8},Cint),length(params),start,params,sep,mod)
#    if result == C_NULL
#        error("oauth_serialize_url_sep failed")
#    end
#    return bytestring(result)
#end

#This one skips the first parameter for some reason?
#Feels like should also write a Dict method, which seems more natural to me
#function oauth_serialize_url_parameters(params::Array)
#    #argc = length(params)
#    result = ccall((:oauth_serialize_url_parameters,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Ptr{Uint8}}),length(params),params)
#    if result == C_NULL
#        error("oauth_serialize_url_parameters")
#    end
#    return bytestring(result)
#end

#What is use case to compare two strings for OAuth? Is this if you're building an API?
#From documentation example, seems like only use is within C qsort, so this shouldn't be Julia function? - Pure Julia
function oauth_cmpstringp(string1::String, string2::String)
    
    return string1 == string2

end

#function oauth_param_exists(argv::Ptr{Ptr{Uint8}},argc::Integer,key::String)
#    result = ccall((:oauth_param_exists,LIBOAUTH),Cint,(Ptr{Ptr{Uint8}},Cint,Ptr{Uint8}),argv,argc,key)
#    if result == C_NULL
#        error("oauth_param_exists failed")
#    end
#    return bytestring(result)
#end

















#Decodes a base64 string
function oauth_decode_base64(source::String)
    dest = Array(Uint8)
    result = ccall((:oauth_decode_base64,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8}),dest,source)
    if result == C_NULL
        error("oauth_decode_base64 failed")
    end
    return bytestring(convert(Ptr{Uint8}, dest))
end



#Returns hashed body as url parameter
function oauth_body_hash_data(data::String)
    result = ccall((:oauth_body_hash_data,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Uint8}),length(data),data)
    if result == C_NULL
        error("oauth_body_hash_data failed")
    end
    return bytestring(result)
end

function oauth_body_hash_file(filename::String)
    result = ccall((:oauth_body_hash_file,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},),filename)
    if result == C_NULL
        error("oauth_body_hash_file failed")
    end
    return bytestring(result)
end

#Is this necessary? Comparing two strings in constant time? Or is this if you're building an API? 
#Docs say 'wrapper to oauth_time_independent_equals_n which calls strlen() for each argument', so we don't need both, right? (if any at all)
function oauth_time_independent_equals(a::String,b::String)
    result = ccall((:oauth_time_independent_equals,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8}),a,b)
    if result == C_NULL
        error("oauth_time_independent_equals failed")
    end
    return bool(result)
end









#'url-escape strings and concatenate with '&' separator.' 
#Works as-is with single argument; how to make variable args/array?
#Or just re-write in Julia?
function oauth_catenc(argv::String)
    result = ccall((:oauth_catenc,LIBOAUTH),Ptr{Uint8},(Ptr{Cint},Ptr{Uint8}),1, argv)
    if result == C_NULL
        error("oauth_catenc failed")
    end
    return bytestring(result)
end








#Unnecessary? Using C to check if a parameter exists in a Julia array seems overkill
#Switched type to Integer and String. Like above, if argv just length of array, should we move inside function?
#function oauth_param_exists(argv::Ptr{Ptr{Uint8}},argc::Integer,key::String)
#    result = ccall((:oauth_param_exists,LIBOAUTH),Cint,(Ptr{Ptr{Uint8}},Cint,Ptr{Uint8}),argv,argc,key)
#    if result == C_NULL
#        error("oauth_param_exists failed")
#    end
#    return bytestring(result)
#end

#Unnecessary, same reason as above? Don't need liboauth to add things to Julia arrays
#function oauth_add_param_to_array(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},addparam::Ptr{Uint8})
#    result = ccall((:oauth_add_param_to_array,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Uint8}),argcp,argvp,addparam)
#    if result == C_NULL
#        error("oauth_add_param_to_array failed")
#    end
#    return bytestring(result)
#end

#Pretty sure this is the MAIN function to make any API calls
function oauth_sign_url2(url::Ptr{Uint8},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_url2,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),url,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_url2 failed")
    end
    return bytestring(result)
end

function oauth_sign_array2_process(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_array2_process,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),argcp,argvp,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_array2_process failed")
    end
    return bytestring(result)
end

function oauth_sign_array2(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_array2,LIBOAUTH),Ptr{Uint8},(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),argcp,argvp,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_array2 failed")
    end
    return bytestring(result)
end

#Since first argument just length of string, should we move inside function? Modified len Julia argument type
function oauth_body_hash_encode(len::Integer,digest::String)
    result = ccall((:oauth_body_hash_encode,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Uint8}),len,digest)
    if result == C_NULL
        error("oauth_body_hash_encode failed")
    end
    return bytestring(result)
end

function oauth_sign_xmpp(xml::String,method::OAuthMethod,c_secret::String,t_secret::String)
    result = ccall((:oauth_sign_xmpp,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},OAuthMethod,Ptr{Uint8},Ptr{Uint8}),xml,method,c_secret,t_secret)
    if result == C_NULL
        error("oauth_sign_xmpp failed")
    end
    return bytestring(result)
end

end # module
