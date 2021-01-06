rule signature_60
{
	meta:
		author = "0xlsd"
		sample = "3bc6ab721f878246ff7ef6df4c28f34c8cd1080bc47cfb3e673e529fcb7fa6dc"
	
		strings:
		$string_1 = {
			02 01
			0B 01
			08 00
			00 FA
			05 00 00 06 00
			00 00
			00 00
			00 FE
			18 06
			00 00
			20 00
			00 00
			00 00
			00 00
			00 40 ??
			00 20
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
