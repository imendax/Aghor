rule signature_115
{
	meta:
		author = "0xlsd"
		sample = "294ef9dbad2208ab399b71ae3831efaed272fc75f2a9368eaadc3806f1506fd4"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			3F
			00 B9 ?? ?? ?? ??
			08 7B ??
			D7
		}
	
	condition:
		any of them
	
}
