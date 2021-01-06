rule signature_148
{
	meta:
		author = "0xlsd"
		sample = "3e585e1cb3876efd010c51152e7d07ac12c4e647fcfba1b51b5c9b32947a2898"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 02
			32 00
			F8
			01 00
			00 BC 00 ?? ?? ?? ??
			00 30
			13 00
			00 00
			10 00
			00 00
			10 02
			00 00
			00 40 ??
			00 10
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
