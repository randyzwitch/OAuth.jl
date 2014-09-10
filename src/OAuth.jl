#Wrapper around liboauth POSIX-c functions implementing the OAuth Core RFC 5849 standard
#http://liboauth.sourceforge.net/index.html

module OAuth

#These seem unnecessary
#const LIBOAUTH_VERSION = "1.0.3"
#const LIBOAUTH_VERSION_MAJOR = 1
#const LIBOAUTH_VERSION_MINOR = 0
#const LIBOAUTH_VERSION_MICRO = 3
#const LIBOAUTH_CUR = 8
#const LIBOAUTH_REV = 7
#const LIBOAUTH_AGE = 8

# Skipping MacroDefinition: OA_GCC_VERSION_AT_LEAST ( x , y ) ( __GNUC__ > x || __GNUC__ == x && __GNUC_MINOR__ >= y )
# Skipping MacroDefinition: attribute_deprecated __attribute__ ( ( deprecated ) )

########################################################################################
#
#
#	Exports & Constants
#
#
########################################################################################

export 
oauth_gen_nonce,
oauth_sign_hmac_sha1,
oauth_sign_hmac_sha1_raw,
oauth_sign_plaintext #,
#oauth_sign_rsa_sha1,
#oauth_verify_rsa_sha1,
#oauth_split_url_parameters,
#oauth_split_post_parameters,
#oauth_serialize_url,
#oauth_serialize_url_sep,
#oauth_serialize_url_parameters,
#oauth_cmpstringp,
#oauth_param_exists,
#oauth_add_param_to_array,
#oauth_free_array,
#oauth_time_independent_equals_n,
#oauth_time_independent_equals,
#oauth_sign_url2,
#oauth_sign_array2_process,
#oauth_sign_array2,
#oauth_body_hash_file,
#oauth_body_hash_data,
#oauth_body_hash_encode,
#oauth_sign_xmpp
#oauth_encode_base64
#oauth_decode_base64
#oauth_url_escape
#oauth_url_unescape
#oauth_catenc

# begin enum ANONYMOUS_1
typealias ANONYMOUS_1 Uint32
const OA_HMAC = (uint32)(0)
const OA_RSA = (uint32)(1)
const OA_PLAINTEXT = (uint32)(2)
# end enum ANONYMOUS_1

# begin enum OAuthMethod
typealias OAuthMethod Uint32
const OA_HMAC = (uint32)(0)
const OA_RSA = (uint32)(1)
const OA_PLAINTEXT = (uint32)(2)
# end enum OAuthMethod



#TODO: Make this generic for all operating systems
#Do we need to use Homebrew or BinDeps to install liboauth for people or assume they installed themselves?
@osx? (const LIBOAUTH = "/usr/local/lib/liboauth.dylib")
@windows? ()
@linux?()
@unix?()

########################################################################################
#
#
#	Functions - According to documentation, Clang.jl didn't generate all functions
#
#
########################################################################################

#Seems correct, returns random string
function oauth_gen_nonce()
    result = ccall((:oauth_gen_nonce,LIBOAUTH),Ptr{Uint8},())
    if result == C_NULL
        error("oauth_gen_nonce failed")
    end
    return bytestring(result)
end

#Should be correct
function oauth_sign_hmac_sha1(url::String,key::String)
    result = ccall((:oauth_sign_hmac_sha1,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),url,key)
    if result == C_NULL
        error("oauth_sign_hmac_sha1 failed")
    end
    return bytestring(result)
end

#Is this right? Do I need to convert the first Ptr{Uint8} in ccall to String type?
function oauth_sign_hmac_sha1_raw(message::String,messagelength::Integer,key::String,keylength::Integer)
    result = ccall((:oauth_sign_hmac_sha1_raw,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Cint,Ptr{Uint8},Cint),message,messagelength,key,keylength)
    if result == C_NULL
        error("oauth_sign_hmac_sha1_raw failed")
    end
    return bytestring(result)
end

#Is this right? Not sure of value of this function, if it just returns the key value
function oauth_sign_plaintext(message::String,key::String)
    result = ccall((:oauth_sign_plaintext,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),message,key)
    if result == C_NULL
        error("oauth_sign_plaintext failed")
    end
    return bytestring(result)
end

function oauth_sign_rsa_sha1(m::Ptr{Uint8},k::Ptr{Uint8})
    result = ccall((:oauth_sign_rsa_sha1,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),m,k)
    if result == C_NULL
        error("oauth_sign_rsa_sha1 failed")
    end
    return bytestring(result)
end

function oauth_verify_rsa_sha1(m::Ptr{Uint8},c::Ptr{Uint8},s::Ptr{Uint8})
    result = ccall((:oauth_verify_rsa_sha1,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),m,c,s)
    if result == C_NULL
        error("oauth_verify_rsa_sha1 failed")
    end
    return bytestring(result)
end

function oauth_split_url_parameters(url::Ptr{Uint8},argv::Ptr{Ptr{Ptr{Uint8}}})
    result = ccall((:oauth_split_url_parameters,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Ptr{Ptr{Uint8}}}),url,argv)
    if result == C_NULL
        error("oauth_split_url_parameters failed")
    end
    return bytestring(result)
end

function oauth_split_post_parameters(url::Ptr{Uint8},argv::Ptr{Ptr{Ptr{Uint8}}},qesc::Int16)
    result = ccall((:oauth_split_post_paramters,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Ptr{Ptr{Uint8}}},Int16),url,argv,qesc)
    if result == C_NULL
        error("oauth_split_post_paramters failed")
    end
    return bytestring(result)
end

function oauth_serialize_url(argc::Cint,start::Cint,argv::Ptr{Ptr{Uint8}})
    result = ccall((:oauth_serialize_url,LIBOAUTH),Ptr{Uint8},(Cint,Cint,Ptr{Ptr{Uint8}}),argc,start,argv)
    if result == C_NULL
        error("oauth_serialize_url failed")
    end
    return bytestring(result)
end

function oauth_serialize_url_sep(argc::Cint,start::Cint,argv::Ptr{Ptr{Uint8}},sep::Ptr{Uint8},mod::Cint)
    result = ccall((:oauth_serialize_url_sep,LIBOAUTH),Ptr{Uint8},(Cint,Cint,Ptr{Ptr{Uint8}},Ptr{Uint8},Cint),argc,start,argv,sep,mod)
    if result == C_NULL
        error("oauth_serialize_url_sep failed")
    end
    return bytestring(result)
end

function oauth_serialize_url_parameters(argc::Cint,argv::Ptr{Ptr{Uint8}})
    result = ccall((:oauth_serialize_url_parameters,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Ptr{Uint8}}),argc,argv)
    if result == C_NULL
        error("oauth_serialize_url_parameters")
    end
    return bytestring(result)
end

function oauth_cmpstringp(p1::Ptr{Void},p2::Ptr{Void})
    result = ccall((:oauth_cmpstringp,LIBOAUTH),Cint,(Ptr{Void},Ptr{Void}),p1,p2)
    if result == C_NULL
        error("oauth_cmpstringp failed")
    end
    return bytestring(result)
end

function oauth_param_exists(argv::Ptr{Ptr{Uint8}},argc::Cint,key::Ptr{Uint8})
    result = ccall((:oauth_param_exists,LIBOAUTH),Cint,(Ptr{Ptr{Uint8}},Cint,Ptr{Uint8}),argv,argc,key)
    if result == C_NULL
        error("oauth_param_exists failed")
    end
    return bytestring(result)
end

function oauth_add_param_to_array(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},addparam::Ptr{Uint8})
    result = ccall((:oauth_add_param_to_array,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Uint8}),argcp,argvp,addparam)
    if result == C_NULL
        error("oauth_add_param_to_array failed")
    end
    return bytestring(result)
end

function oauth_free_array(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}})
    result = ccall((:oauth_free_array,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}}),argcp,argvp)
    if result == C_NULL
        error("oauth_free_array failed")
    end
    return bytestring(result)
end

function oauth_time_independent_equals_n(a::Ptr{Uint8},b::Ptr{Uint8},len_a::Cint,len_b::Cint)
    result = ccall((:oauth_time_independent_equals_n,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8},Cint,Cint),a,b,len_a,len_b)
    if result == C_NULL
        error("oauth_time_independent_equals_n failed")
    end
    return bytestring(result)
end

function oauth_time_independent_equals(a::Ptr{Uint8},b::Ptr{Uint8})
    result = ccall((:oauth_time_independent_equals,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8}),a,b)
    if result == C_NULL
        error("oauth_time_independent_equals failed")
    end
    return bytestring(result)
end

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

function oauth_body_hash_file(filename::Ptr{Uint8})
    result = ccall((:oauth_body_hash_file,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},),filename)
    if result == C_NULL
        error("oauth_body_hash_file failed")
    end
    return bytestring(result)
end

function oauth_body_hash_data(length::Cint,data::Ptr{Uint8})
    result = ccall((:oauth_body_hash_data,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Uint8}),length,data)
    if result == C_NULL
        error("oauth_body_hash_data failed")
    end
    return bytestring(result)
end

function oauth_body_hash_encode(len::Cint,digest::Ptr{Cuchar})
    result = ccall((:oauth_body_hash_encode,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Cuchar}),len,digest)
    if result == C_NULL
        error("oauth_body_hash_encode failed")
    end
    return bytestring(result)
end

function oauth_sign_xmpp(xml::Ptr{Uint8},method::OAuthMethod,c_secret::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_xmpp,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},OAuthMethod,Ptr{Uint8},Ptr{Uint8}),xml,method,c_secret,t_secret)
    if result == C_NULL
        error("oauth_sign_xmpp failed")
    end
    return bytestring(result)
end

function oauth_encode_base64()
    error("Not yet implemented")
end

function oauth_decode_base64()
    error("Not yet implemented")
end

function oauth_url_escape()
    error("Not yet implemented")
end

function oauth_url_unescape()
    error("Not yet implemented")
end

function oauth_catenc()
    error("Not yet implemented")
end

end # module
