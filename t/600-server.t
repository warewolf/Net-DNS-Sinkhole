use Test::More;

use strict;
use warnings;


BEGIN { use_ok('Net::DNS::Sinkhole::Handler::Whitelist'); }

my $whitelist_handler = new_ok( 'Net::DNS::Sinkhole::Handler::Whitelist');
isa_ok( $whitelist_handler, 'Net::DNS::Sinkhole::Handler' );
can_ok( 'Net::DNS::Sinkhole::Handler::Whitelist', 'handler' );
$whitelist_handler->trie->add("microsoft.com");


BEGIN { use_ok('Net::DNS::Sinkhole::Handler::Blacklist'); }
my $blacklist_handler = new_ok( 'Net::DNS::Sinkhole::Handler::Blacklist');
isa_ok( $blacklist_handler, 'Net::DNS::Sinkhole::Handler' );
can_ok( 'Net::DNS::Sinkhole::Handler::Blacklist', 'handler' );

my $blacklist_records = {
  records => {
    A  => '* 86400 IN A 10.1.2.3',
    NS => '* 86400 IN NS ns.sinkhole.example.com',
    SOA => '* 86400 IN SOA ns.sinkhole.example.com. cert.example.com.  ( 42 28800 14400 3600000 86400)',
  },
};

$blacklist_handler->trie->add_data("dyndns.org" => $blacklist_records) ;
$blacklist_handler->trie->add_data("ns.sinkhole.example.com" => $blacklist_records) ;

BEGIN { use_ok('Net::DNS::Sinkhole::Resolver'); }
my $blacklist_resolver = new_ok('Net::DNS::Sinkhole::Resolver' => [resolver_object => $blacklist_handler]);
my $whitelist_resolver = new_ok('Net::DNS::Sinkhole::Resolver' => [resolver_object => $whitelist_handler]);



BEGIN { use_ok('Net::DNS::Sinkhole::Server'); }
my $server = new_ok( 'Net::DNS::Sinkhole::Server' =>
  [
    AutoWhitelist => 1,
    AutoBlacklist => 1,
    BlackList => $blacklist_resolver,
    WhiteList => $whitelist_resolver,
    LocalAddr=>[qw(127.0.0.1)],
    LocalPort=>5252,
  ]
);

done_testing();
