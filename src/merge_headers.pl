#!/usr/bin/perl -w

# put a bunch of headers together into one header, expanding
#  in place of first reference

@headers= @ARGV;
$fhnonce= 'h00000';

%done= ();
foreach $header (@headers) {
    &process($header) unless $done{$header};
}

sub process {
    my $header= shift;
    $done{$header}= 1;
    
    my $fh= $fhnonce++;
    my $line;
    open($fh,"<$header") || die "could not open $header";
    while ($line= <$fh>) {
        if ($line =~ s/\#include\s+\"([^\"]+)\"//) {
            $incl= $1;
            if (!$done{$incl}) {
                #print "/*===========> from $incl */\n";
                &process($incl);
                #print "/* from $incl <=========== */\n";
            }
        }
        # pass through
        print $line;
    }
    close $fh;
}