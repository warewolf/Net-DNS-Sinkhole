use Test::More;

use strict;
use warnings;

BEGIN { use_ok('Net::DNS::Sinkhole::Trie'); }

my $trie = new_ok( 'Net::DNS::Sinkhole::Trie');
isa_ok( $trie, 'Tree::Trie' );

can_ok( 'Net::DNS::Sinkhole::Trie', 'clone_record' );

is( $trie->add('example.com'),1, 'Trie scalar add scalar context returns number of elements added' );

# this just looks to pretty (and obvious) to leave out.
# So I _really_ hope that Tree::Trie > v1.8 doesn't change its internal data structure.
is_deeply($trie->{_MAINHASHREF}, {
'm' => {
'o' => {
'c' => {
'.' => {
'e' => { 
'l' => {
'p' => {
'm' => {
'a' => {
'x' => {
'e' => {
'' => undef } } } } } } } } } } } },
'Trie structure is reversed for efficiency');

is( $trie->add(qw(yahoo.com google.com bing.com)),3, 'Trie list add scalar context returns number of elements added' );

is ( $trie->lookup('example.com'), 'example.com', 'Trie lookup reverses return value in scalar context');
is ( $trie->lookup('EXAMPLE.COM'), 'example.com', 'Trie add quashes case');

is_deeply( [$trie->add('mtfnpy.com')] , ["mtfnpy.com"] , 'Trie basic add list context return values are reversed' );
is_deeply( [$trie->add('ZGSACL.com')] , ["zgsacl.com"] , 'Trie basic add list context return values are reversed and quashed' );


eval { $trie->add(\[qw(e x a m p l e . c o m)]); };
like ($@,qr/Adding references is unsupported/,"Trie add reference fails");

my $ref = { this => 'that', mtfnpy => [qw(awesome awesome awesome awesome)]};

$trie->add_data('example.com',$ref);
ok ( $trie->lookup_data('example.com') == $ref, 'Trie added data retrieval');

$trie->clone_record('example.com' => 'example.org');

is ( $trie->lookup('example.org'), 'example.org', 'Trie clone lookup');

ok ( $trie->lookup_data('example.org') == $ref, 'Trie clone data retrieval dest matches source');
done_testing();
