#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <ctime> 
#include <cmath>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <curl/curl.h>

// compile with g++ api.cpp -lcurl -lssl -lcrypto -o zxapi

// super simple curl exception class.
class CurlEx {};

// curl wrapper. just enough to do a simple HTTP GET with custom headers.
class Curl
{
public:
    Curl()
        :headers_(0)
    {
        init();
    }
    
    Curl(const std::string& u)
        :headers_(0)
    {
        init();
        url(u);
    }    

    ~Curl()
    {
        curl_easy_cleanup(curl_);
        if(headers_ != NULL)
        {
            curl_slist_free_all(headers_ );        
        }
    }
        
    Curl& url(const std::string& u)
    {
        curl_easy_setopt(curl_, CURLOPT_URL, u.c_str() );
        return *this;
    }
      
    Curl& header(const std::string& key, const std::string& val)
    {
        std::ostringstream oss;
        oss << key << ":" << val;
        headers_ = curl_slist_append(headers_, oss.str().c_str() );
        return *this;
    }
    
    Curl& verbose()
    {
        curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);
        return *this;
    }

    Curl& perform()
    {
        CURLcode res = CURLE_OK;
        if(headers_ != NULL)
        {
            curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers_);
        }
        
        res = curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, &Curl::callback);
        if (res != CURLE_OK)
        {
            throw CurlEx();
        }
         
        res = curl_easy_setopt(curl_, CURLOPT_WRITEDATA, this);
        if (res != CURLE_OK)
        {
            throw CurlEx();
        }
    
        res = curl_easy_perform(curl_);
        if (res != CURLE_OK)
        {
            throw CurlEx();
        }
        return *this;
    }
    
    std::string response_body()
    {
        return oss_.str();
    }
    
private:

    static int callback(char *data, size_t size, size_t nmemb, Curl* that)
    {
        that->oss_ << std::string(data,size*nmemb);
        return size * nmemb;
    }
    
    void init()
    {
        curl_ = curl_easy_init();
        if(!curl_) 
        {
            throw new CurlEx();
        }
    }

    CURL* curl_;
    struct curl_slist* headers_;
    std::ostringstream oss_;
};

// Buffer Helper, mainly to avoid some malloc/free calls. RAII rules.
class Buf
{
public:

    Buf(size_t s)
        : buf_(s,0)
    {}
    
    unsigned char* operator&()
    {
        return &(buf_[0]);
    }
    
    unsigned char& operator[](size_t i)
    {
        return buf_[i];
    }
    
    std::string toString()
    {
        return std::string( (char*)&(buf_[0]), buf_.size() );
    }

private:
    std::vector<unsigned char> buf_;
};

// the openssl way to base64encode a given string. sigh.
std::string Base64Encode(const unsigned char* message,size_t s) { 

    BIO *bio, *b64;
    FILE* stream;
    int encodedSize = 4*ceil((double)s/3);
    Buf buffer(encodedSize+1);
     
    stream = fmemopen(&buffer, encodedSize+1, "w");
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
    BIO_write(bio, message, s);
    BIO_flush(bio);
    BIO_free_all(bio);
    fclose(stream);
    
    return buffer.toString();
}

// use openssl to build a base64-encoded sha1 HMAC with given key and msg.
std::string hmac_sha1( const std::string& key, const std::string& msg)
{
    unsigned char* secret   = (unsigned char*) key.c_str();
    unsigned char* data     = (unsigned char*) msg.c_str();
    unsigned int result_len = 0;
    
    Buf buffer(EVP_MAX_MD_SIZE);    
    HMAC(EVP_sha1(), secret, key.size(), data, msg.size(), &buffer, &result_len);
    return Base64Encode(&buffer,result_len);
}

// generate a random nonce using openssl.
std::string make_nonce(size_t s)
{
    Buf buf(s);
    
    // fill buffer with random bytes
    RAND_pseudo_bytes(&buf,s);
    
    // assert that the bytes actually are char values from A-Z
    for ( size_t i = 0; i < s; i++)
    {
        unsigned char c = buf[i];
        buf[i] = c % 26 + 65;
    }
    return buf.toString();
}

// get the current time in UTC, ie "Fri, 07 Mar 2014 20:09:05 GMT"
std::string utc_time()
{
    time_t rawtime;
    time (&rawtime);

    struct tm  timeinfo;
    timeinfo = *gmtime (&rawtime);
    
    char buffer [256];
    strftime (buffer,256,"%a, %d %b %Y %H:%M:%S GMT",&timeinfo);
    return buffer;
}

    
// zx api constants
const std::string prefix = "ZXWS";
const std::string datatype = "xml";
const std::string version = "2011-03-01";
const std::string host = "api.zanox.com";

// zanox Publisher API.
class zxApi
{
public:
    zxApi( const std::string& cid, const std::string& secret)
        : cid_(cid), secret_(secret)
    {}
    
    std::string call(const std::string& path, const std::string& params)
    {
        // construct the api HTTP path
        std::string url = "/" + datatype + "/" + version + path;
        
        // get nonce for zx auth
        std::string nonce = make_nonce(20);
        
        // get the current time in utc format (GMT)
        std::string now = utc_time();
        
        // the signature to be HMACed for authentication
        std::string sig = std::string("GET") + path + now + nonce;
        
        // construct HMAC
        std::string auth = hmac_sha1(secret_,sig);
        
        // now use curl to retrieve the data
        std::string response =
            Curl( std::string("http://") + host + url + params)
            .verbose() // shows header info on stderr
            .header("Accept","application/json")
            .header("Host",host)
            .header("Date",now)
            .header("Nonce",nonce)
            .header("Authorization", prefix + " " + cid_ + ":" + auth)
            .perform()
            .response_body();
            
        return response;
    }
    
private:
    std::string cid_;
    std::string secret_;  
};
    
// main program
int main(int argc, char** args)
{
    // usage
    if ( argc < 4 ) 
    {
        std::cerr 
            << "usage: zxapi <connectid> <secretkey> <path> [param1=value[&param2=value...]]" 
            << std::endl;
            
        exit(0);
    }
    
    // command line args handling
    std::string cid    = args[1];
    std::string secret = args[2];
    std::string path   = args[3];
    std::string params = "";
    
    if ( argc > 4 )
    {
        params = std::string("?") + args[4];
    }
    
    // construct a zxApi object to make calls to publisher api.
    zxApi api(cid,secret);
    
    // call api and fetch result.
    std::string result = api.call(path,params);
    
    // can do whatever you want with your xml now. here we just print to stdout.
    std::cout << result << std::endl;    
    
    return 0;
}
    

