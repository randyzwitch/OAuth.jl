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
@test oauth_sign_plaintext(testurl, testkey) == testkey

#oauth_encode_base64
#Returns base64 encoded
@test oauth_encode_base64("RandyZwitch") == "UmFuZHlad2l0Y2g="

#oauth_url_escape
#Returns encoded string
@test oauth_url_escape("http://randyzwitch.com/") == "http%3A%2F%2Frandyzwitch.com%2F"

#oauth_url_unescape
#Returns original string from encoded string
@test oauth_url_unescape(oauth_url_escape("http://randyzwitch.com/")) == "http://randyzwitch.com/"