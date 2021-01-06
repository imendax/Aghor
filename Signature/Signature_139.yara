rule signature_139
{
	meta:
		author = "0xlsd"
		sample = "302d13bcee6a2cc92a3febeb5d25d4407b5f7b011c3328ba1e22fb3b4cc483c3"
	
	
	strings:
		$string_1 = {
			0F 03 0B
			01 06
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 E0
			11 00
			00 00
			10 00
			00 00
			20 00
			00 00
			00 40 ??
			00 10
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
