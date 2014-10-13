using OAuth
using Base.Test

# write your own tests here

#oauth_gen_nonce
#Returns random string
@test typeof(oauth_gen_nonce()) <: String

#oauth_sign_hmac_sha1
#Returns 
testurl = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
testkey = "kd94hf93k423kf44&pfkkdhi9sl3r4s00"
@test oauth_sign_hmac_sha1(testurl, testkey) == "tR3+Ty81lMeYAr/Fid0kMTYa/WM="

#oauth_sign_hmac_sha1_raw
#Same as oauth_sign_hmac_sha1, except you can specify length if there are null characters
testurl = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
urllen = length(testurl)
testkey = "kd94hf93k423kf44&pfkkdhi9sl3r4s00"
keylen = length(testkey)

@test oauth_sign_hmac_sha1_raw(testurl, urllen, testkey, keylen) == "tR3+Ty81lMeYAr/Fid0kMTYa/WM="

#oauth_sign_plaintext
#Not sure what benefit of this function is, just returns key?
testurl = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"
testkey = "kd94hf93k423kf44&pfkkdhi9sl3r4s00"
#@test oauth_sign_plaintext(testurl, testkey) == testkey

#oauth_encode_base64
#Returns base64 encoded
@test oauth_encode_base64("RandyZwitch") == "UmFuZHlad2l0Y2g="

#oauth_url_escape
#Returns encoded string
@test oauth_url_escape("http://randyzwitch.com/") == "http%3A%2F%2Frandyzwitch.com%2F"

#oauth_url_unescape
#Returns original string from encoded string
@test oauth_url_unescape(oauth_url_escape("http://randyzwitch.com/")) == "http://randyzwitch.com/"

#oauth_serialize_url_parameters
#Takes array, returns string of &-separated parameters (skipping the first one)
@test oauth_serialize_url_parameters(["Randy=Awesome", "Zwitch=Cool", "Julia=Fun"]) == "Zwitch=Cool&Julia=Fun"

#oauth_serialize_url
#Takes array, allows for starting somewhere other than entire array, returns string of &-separated parameters
@test oauth_serialize_url(["Randy=Awesome", "Zwitch=Cool", "Julia=Fun"], 1) == "Zwitch=Cool&Julia=Fun"

#Decodes base64 string, returning original string
@test oauth_decode_base64(oauth_encode_base64("RandyZwitch")) == "RandyZwitch"

#Takes array, returns string separated by value
#last argument needs documentation (1, 2 or 4 acceptable values)
@test oauth_serialize_url_sep(["randy=zwitch", "julia=language","clang=codegenerator"], "&", 0, 1) == "randy=zwitch&julia=language&clang=codegenerator"

#Takes string, returns hashed body as url parameter
@test oauth_body_hash_data("randy") == "oauth_body_hash=aFB6E2Zew6MXWcDTqUgEIhwKh9M="

#Takes url parameter string, returns array of values
@test oauth_split_url_parameters("?julia=0.4&packages=400&speed=fantastic") == ["julia=0.4","packages=400","speed=fantastic"]

#true treats '+' as null space
@test oauth_split_post_parameters("?julia=0.4&packages=400&speed=fantastic", true) == ["julia=0.4","packages=400","speed=fantastic"]

#false keeps '+' as an actual character
@test oauth_split_post_parameters("?julia=0.4&packages=400&speed=fantastic", false) == ["julia=0.4","packages=400+","speed=fantastic"]

#Takes file, reads, returns oauth_body_hash string
#@test oauth_body_hash_file(Pkg.dir("OAuth", "test", "randy.txt")) == "oauth_body_hash=9A1WNYRsC819CwKI768PbcMXwIg="


