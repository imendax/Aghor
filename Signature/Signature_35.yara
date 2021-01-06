rule signature_35
{
	meta:
		author = "0xlsd"
		sample = "63169f0b4441e2e6e0ac7391abd05d824e44f19d3902665c5b9e0b434f999f9c"
	
	
	strings:
		$string_1 = {
			0F 01 0B
			01 05 ?? ?? ?? ??
			00 00
			24 07
			00 00
			00 00
			00 78 ??
			00 00
			00 10
			00 00
			00 D0
			00 00
			00 00
			40
			00 00
			10 00
			00 00
		}
	
	condition:
		any of them
	
}
