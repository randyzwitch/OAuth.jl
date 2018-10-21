using OAuth, Test


@test typeof(oauth_timestamp()) <: AbstractString

@test parse(Int, oauth_timestamp()) > 1422235471

@test typeof(oauth_nonce(15)) <: AbstractString

@test length(oauth_nonce(15)) == 15
@test length(oauth_nonce(20)) == 20
@test length(oauth_nonce(25)) == 25
@test length(oauth_nonce(30)) == 30
@test length(oauth_nonce(32)) == 32

@test oauth_sign_hmac_sha1("randy", "zwitch") == "WqKCG5iyhFiES3fWYVdWJWwinaY="

@test oauth_signing_key("9djdj82h48djs9d2", "kkk9d7dh3k39sjv7") == "9djdj82h48djs9d2&kkk9d7dh3k39sjv7"

@test oauth_signature_base_string("POST", "http://example.com", "?julia=fast&lang=elegant") ==
        "POST&http%3A%2F%2Fexample.com&%3Fjulia%3Dfast%26lang%3Delegant"

@test oauth_percent_encode_keys!(Dict("badkey!"   => "value", "goodkey" => "value")) == Dict("badkey%21" => "value", "goodkey" => "value")

@test oauth_serialize_url_parameters(Dict("language" => "julia", "result" => "awesome")) == "language=julia&result=awesome"

@test encodeURI!(Dict("iv" => 10, "s" => "value!")) == Dict("iv" => 10, "s" => "value%21")

@test oauth_body_hash_encode("Hello, World!") == "CgqfKmdylCVXq1NV12r0Qvj2XgE="

@test oauth_body_hash_data("Hello, World!") == "oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="

test_file = joinpath(dirname(@__FILE__), "auth_body_hash_file.txt")
@test oauth_body_hash_file(test_file) == "oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="

#TODO
#oauth_header()

#TODO
#oauth_request_resource()
