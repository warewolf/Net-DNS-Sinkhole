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


$blacklist_handler->trie->add_data("dyndns.com" => $blacklist_records);
$blacklist_handler->trie->add_data("sinkhole.example.com" => $blacklist_records);

BEGIN { use_ok('Net::DNS::Sinkhole::Resolver'); }
my $resolver = new_ok('Net::DNS::Sinkhole::Resolver' => [resolver_object => $blacklist_handler]);
isa_ok($resolver,'Net::DNS::Resolver::Programmable');
isa_ok($resolver,'Net::DNS::Resolver');
can_ok( 'Net::DNS::Sinkhole::Resolver', 'send' );
can_ok( 'Net::DNS::Sinkhole::Resolver', 'resolver' );
is($resolver->resolver(),$blacklist_handler,"Resolver object returns handler");

my $answer = $resolver->send( "www.dyndns.com", "A", "IN" );
is($answer->header->rcode,"NOERROR","Resolver blacklisted returns record");

$answer = $resolver->send( "www.richardharman.com", "A", "IN" );
is($answer->header->rcode,"IGNORE","Resolver non-blacklisted returns IGNORE");

done_testing();
