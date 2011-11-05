use Test::More;

use strict;
use warnings;

BEGIN { use_ok('Net::DNS::Sinkhole::Handler::Whitelist'); }
my $whitelist_handler = new_ok( 'Net::DNS::Sinkhole::Handler::Whitelist');
isa_ok( $whitelist_handler, 'Net::DNS::Sinkhole::Handler' );
can_ok( 'Net::DNS::Sinkhole::Handler::Whitelist', 'handler' );
$whitelist_handler->trie->add("microsoft.com");
my ( $rcode) = $whitelist_handler->handler("www.microsoft.com");
is($rcode,"NOERROR","Whitelisted domain lookup success");
( $rcode ) = $whitelist_handler->handler("www.richardharman.com");
is($rcode,"IGNORE","Non-whitelisted domain lookup ignored");

BEGIN { use_ok('Net::DNS::Sinkhole::Resolver'); }
my $resolver = new_ok('Net::DNS::Sinkhole::Resolver' => [resolver_object => $whitelist_handler]);
isa_ok($resolver,'Net::DNS::Resolver::Programmable');
isa_ok($resolver,'Net::DNS::Resolver');
can_ok( 'Net::DNS::Sinkhole::Resolver', 'send' );
can_ok( 'Net::DNS::Sinkhole::Resolver', 'resolver' );
is($resolver->resolver(),$whitelist_handler,"Resolver object returns handler");

done_testing();
