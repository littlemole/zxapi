use POSIX qw(strftime locale_h);
use Digest::SHA qw(hmac_sha1_base64);
use LWP::UserAgent;
use strict;

my $prefix = "ZXWS";
my $datatype = "json";
my $version = "2011-03-01";
my $host = "api.zanox.com";

setlocale(LC_TIME, "en_US.UTF-8");

sub now {
    return strftime( '%a, %d %b %Y %H:%M:%S GMT', gmtime);
}

sub nonce {

    my $size  = shift;
    my $nonce = "";
    
    for ( my $i = 0; $i < $size; $i++) {
        $nonce .= chr( int(rand(25) + 65) ); 
    } 
    return $nonce;
}

sub hmac_sha1 {

    my $key = shift;
    my $msg = shift;
    
    my $mac = hmac_sha1_base64($msg, $key);
    while (length($mac) % 4) {
            $mac .= '=';
    }
    return $mac;      
}    


my $argc = @ARGV;

if ( $argc < 3 ) {
  print "usage : api.pl <cid> <secret> <path> \r\n";
  print "with: cid - connect id \r\n";
  print "      secret - api secret key \r\n";
  print "      path - api method to call, ie /profiles \r\n";
  exit(0);
}

my $cid    = $ARGV[0];
my $secret = $ARGV[1];
my $call   = $ARGV[2];

my $nonce  = nonce(20);
my $now    = now();

my $auth = hmac_sha1( $secret, "GET" . $call . $now . $nonce );

my $httpClient = LWP::UserAgent->new();

my $req = HTTP::Request->new(
    GET => 'http://' . $host . "/" . $datatype . "/" . $version . $call 
);

$req->header(
    "Accept" => "application/json",
    "Host"   =>  $host,
    "Date"   =>  $now,
    "Nonce"  =>  $nonce,
    "Authorization" =>  $prefix ." " . $cid . ":" . $auth
);
    
my $res = $httpClient->request($req);
print $res->content . "\r\n";


