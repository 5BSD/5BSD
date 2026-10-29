#!/usr/bin/perl
#
# Copyright (c) 1997 Shigio Yamaguchi. All rights reserved.
# Copyright (c) 1999 Tama Communications Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# 

#
# Test script for abs2rel(3) and rel2abs(3).
#
use strict;
use warnings;
use FindBin;
open(my $fixtures, '<', "$FindBin::Bin/cases.tsv") or die "cases.tsv: $!\n";
my ($count, $failures) = (0, 0);
while (my $line = <$fixtures>) {
    next if $line =~ /^#/;
    chomp $line;
    my ($program, $path, $base, $expected) = split(/\t/, $line, -1);
    die "invalid fixture\n" unless defined($expected) && $program =~ /^(abs2rel|rel2abs)$/;
    open(my $child, '-|', "./$program", $path, $base) or die "$program: $!\n";
    my $result = do { local $/; <$child> };
    my $ok = close($child);
    $result = '' unless defined($result);
    chomp $result;
    $count++;
    if (!$ok || $result ne $expected) {
        warn "$program $path $base: expected $expected, got $result\n";
        $failures++;
    }
}
close($fixtures) or die "cases.tsv: $!\n";
print "$count conversion cases, $failures failures\n";
exit($count == 0 || $failures != 0 ? 1 : 0);
