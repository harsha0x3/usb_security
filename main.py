def main():
    print("Hello from usb-security!")


if __name__ == "__main__":
    main()

First request sending the plain username to the server

POST /UserLogin/GetEncPassword HTTP/2
Host: titanrptuat.titan.in
Cookie: UserCookie=ca45e6ab-0ade-4852-8db2-cd0b0ac895b1; .AspNetCore.Antiforgery.9Ss6MOouwnc=CfDJ8MosugdBx8NAsTr8ijk1Mx5pfp048iiLnoaaAsP3ksfYpnvSp01cvMep7wB27cxq-GmtzBT0EAJm9BwlxvUDeW9gP7BhwFIWhCrLhJAS-L_NnKvjZOZnPqWm0K9gDX8j6_GsJ9caKvzrAlT4IOm04Vc; .AspNetCore.Session=CfDJ8MosugdBx8NAsTr8ijk1Mx4Ri3wx%2Bo9dtFkHTByaJPx3%2F%2FE5C5sbx4jfcP9IRiPsx7XiCBcWwdpDuSOYnVSfskCtra%2FqjAyuhx0BKVoZMCJBoS5OmLVr3sneT8LWqucBN5STfr8Ers%2B27q6DR5P7VuRKiJ5mfBC%2F%2FrWLdLe7pN77
Content-Length: 20
Sec-Ch-Ua-Platform: "macOS"
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: */*
Sec-Ch-Ua: "Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Sec-Ch-Ua-Mobile: ?0
Origin: https://titanrptuat.titan.in
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://titanrptuat.titan.in/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Priority: u=0, i

plainpass=vapt.admin

Second request sending the plain password to the server

POST /UserLogin/GetEncPassword HTTP/2
Host: titanrptuat.titan.in
Cookie: .AspNetCore.Antiforgery.9Ss6MOouwnc=CfDJ8MosugdBx8NAsTr8ijk1Mx5pfp048iiLnoaaAsP3ksfYpnvSp01cvMep7wB27cxq-GmtzBT0EAJm9BwlxvUDeW9gP7BhwFIWhCrLhJAS-L_NnKvjZOZnPqWm0K9gDX8j6_GsJ9caKvzrAlT4IOm04Vc; .AspNetCore.Session=CfDJ8MosugdBx8NAsTr8ijk1Mx4Ri3wx%2Bo9dtFkHTByaJPx3%2F%2FE5C5sbx4jfcP9IRiPsx7XiCBcWwdpDuSOYnVSfskCtra%2FqjAyuhx0BKVoZMCJBoS5OmLVr3sneT8LWqucBN5STfr8Ers%2B27q6DR5P7VuRKiJ5mfBC%2F%2FrWLdLe7pN77
Content-Length: 21
Sec-Ch-Ua-Platform: "macOS"
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: */*
Sec-Ch-Ua: "Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Sec-Ch-Ua-Mobile: ?0
Origin: https://titanrptuat.titan.in
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://titanrptuat.titan.in/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Priority: u=0, i

plainpass=V4p7%402025

Third request sending the encrypted password and username to the server

POST /UserLogin/GetEncPassword HTTP/2
Host: titanrptuat.titan.in
Cookie: .AspNetCore.Antiforgery.9Ss6MOouwnc=CfDJ8MosugdBx8NAsTr8ijk1Mx5pfp048iiLnoaaAsP3ksfYpnvSp01cvMep7wB27cxq-GmtzBT0EAJm9BwlxvUDeW9gP7BhwFIWhCrLhJAS-L_NnKvjZOZnPqWm0K9gDX8j6_GsJ9caKvzrAlT4IOm04Vc; .AspNetCore.Session=CfDJ8MosugdBx8NAsTr8ijk1Mx4Ri3wx%2Bo9dtFkHTByaJPx3%2F%2FE5C5sbx4jfcP9IRiPsx7XiCBcWwdpDuSOYnVSfskCtra%2FqjAyuhx0BKVoZMCJBoS5OmLVr3sneT8LWqucBN5STfr8Ers%2B27q6DR5P7VuRKiJ5mfBC%2F%2FrWLdLe7pN77
Content-Length: 382
Sec-Ch-Ua-Platform: "macOS"
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: */*
Sec-Ch-Ua: "Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Sec-Ch-Ua-Mobile: ?0
Origin: https://titanrptuat.titan.in
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://titanrptuat.titan.in/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Priority: u=0, i

plainpass=passData%3D%26Username%3Duq%2BtI1a87NV2IgkcLoM7AQ%3D%3D%26Password%3DE0%2FMrMK7NZL4ahkWNU9Kmg%3D%3D%26domain%3D85ac8c21-9ffd-492b-a189-a03b55eecfe1%26DomainName%3DANBAUTH%26returnurl%3D%26__RequestVerificationToken%3DCfDJ8MosugdBx8NAsTr8ijk1Mx4cCCYhoSedwWw-S3B5VMWUvxfcwnu8YF4ZVdycC9kg3SAc-mf08XwJLJCBqVucOanL_wA6_YuOFVnzeDgZoZXCjhFc6RfA8hkcH77BTmJsFzpFHt5zQKW-Mt8QfC0KmQ0

Final login endpount