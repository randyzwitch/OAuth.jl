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
oauth_sign_hmac_sha1  #,
#oauth_sign_hmac_sha1_raw,
#oauth_sign_plaintext,
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
#	Functions
#
#
########################################################################################

function oauth_sign_hmac_sha1(url::String,key::String)
    result = ccall((:oauth_sign_hmac_sha1,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),url,key)
    if result == C_NULL
        error("oauth_sign_hmac_sha1 failed")
    end
    return bytestring(result)
end

function oauth_sign_hmac_sha1_raw(m::Ptr{Uint8},ml::Cint,k::Ptr{Uint8},kl::Cint)
    result = ccall((:oauth_sign_hmac_sha1_raw,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Cint,Ptr{Uint8},Cint),m,ml,k,kl)
    if result == C_NULL
        error("oauth_sign_hmac_sha1_raw failed")
    end
    return bytestring(result)
end

function oauth_sign_plaintext(m::Ptr{Uint8},k::Ptr{Uint8})
    result = ccall((:oauth_sign_plaintext,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),m,k)
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

#Deprecated
#=
function oauth_time_indepenent_equals_n(a::Ptr{Uint8},b::Ptr{Uint8},len_a::Cint,len_b::Cint)
    ccall((:oauth_time_indepenent_equals_n,liboauth),Cint,(Ptr{Uint8},Ptr{Uint8},Cint,Cint),a,b,len_a,len_b)
end
=#

function oauth_time_independent_equals(a::Ptr{Uint8},b::Ptr{Uint8})
    result = ccall((:oauth_time_independent_equals,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8}),a,b)
    if result == C_NULL
        error("oauth_time_independent_equals failed")
    end
    return bytestring(result)
end

#Deprecated
#=
function oauth_time_indepenent_equals(a::Ptr{Uint8},b::Ptr{Uint8})
    ccall((:oauth_time_indepenent_equals,liboauth),Cint,(Ptr{Uint8},Ptr{Uint8}),a,b)
end
=#

function oauth_sign_url2(url::Ptr{Uint8},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_url2,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),url,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_url2 failed")
    end
    return bytestring(result)
end

#Deprecated
#=function oauth_sign_url(url::Ptr{Uint8},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    ccall((:oauth_sign_url,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),url,postargs,method,c_key,c_secret,t_key,t_secret)
end
=#

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

#Deprecated
#=
function oauth_sign_array(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    ccall((:oauth_sign_array,liboauth),Ptr{Uint8},(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),argcp,argvp,postargs,method,c_key,c_secret,t_key,t_secret)
end
=#

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

#Deprecated
#=
function oauth_http_get(u::Ptr{Uint8},q::Ptr{Uint8})
    ccall((:oauth_http_get,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),u,q)


function oauth_http_get2(u::Ptr{Uint8},q::Ptr{Uint8},customheader::Ptr{Uint8})
    ccall((:oauth_http_get2,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),u,q,customheader)
end

function oauth_http_post(u::Ptr{Uint8},p::Ptr{Uint8})
    ccall((:oauth_http_post,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),u,p)
end

function oauth_http_post2(u::Ptr{Uint8},p::Ptr{Uint8},customheader::Ptr{Uint8})
    ccall((:oauth_http_post2,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),u,p,customheader)
end

function oauth_post_file(u::Ptr{Uint8},fn::Ptr{Uint8},len::Cint,customheader::Ptr{Uint8})
    ccall((:oauth_post_file,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Cint,Ptr{Uint8}),u,fn,len,customheader)
end

function oauth_post_data(u::Ptr{Uint8},data::Ptr{Uint8},len::Cint,customheader::Ptr{Uint8})
    ccall((:oauth_post_data,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Cint,Ptr{Uint8}),u,data,len,customheader)
end


function oauth_post_data_with_callback(u::Ptr{Uint8},data::Ptr{Uint8},len::Cint,customheader::Ptr{Uint8},callback::Ptr{Void},callback_data::Ptr{Void})
    ccall((:oauth_post_data_with_callback,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Cint,Ptr{Uint8},Ptr{Void},Ptr{Void}),u,data,len,customheader,callback,callback_data)
end

function oauth_send_data(u::Ptr{Uint8},data::Ptr{Uint8},len::Cint,customheader::Ptr{Uint8},httpMethod::Ptr{Uint8})
    ccall((:oauth_send_data,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Cint,Ptr{Uint8},Ptr{Uint8}),u,data,len,customheader,httpMethod)
end

function oauth_send_data_with_callback(u::Ptr{Uint8},data::Ptr{Uint8},len::Cint,customheader::Ptr{Uint8},callback::Ptr{Void},callback_data::Ptr{Void},httpMethod::Ptr{Uint8})
    ccall((:oauth_send_data_with_callback,liboauth),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8},Cint,Ptr{Uint8},Ptr{Void},Ptr{Void},Ptr{Uint8}),u,data,len,customheader,callback,callback_data,httpMethod)
end
=#

end # module
