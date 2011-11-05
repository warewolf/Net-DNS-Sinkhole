use Test::More;

use strict;
use warnings;

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
# gotta add the NS records
$blacklist_handler->trie->add_data("ns.sinkhole.example.com" => $blacklist_records) ;

my ($rcode,$answer,$authority,$additional,$headermask) = $blacklist_handler->handler("mtfnpy.dyndns.org","A","IN");
is($rcode,"NOERROR","Blacklisted subdomain lookup success");

($rcode,$answer,$authority,$additional,$headermask) = $blacklist_handler->handler("dyndns.org","A","IN");
is($rcode,"NOERROR","Blacklisted domain lookup success");

($rcode,$answer,$authority,$additional,$headermask) = $blacklist_handler->handler("mtfnpy.org","A","IN");
is($rcode,"IGNORE","Non-blacklisted domain lookup ignored");

done_testing();
