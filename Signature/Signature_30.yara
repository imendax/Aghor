rule signature_30
{
	meta:
		author = "0xlsd"
		sample = "4cdac19663afef8650fba2209714bde767d955171b8f1e6f46ab4a036e1cccd0"
	
	
	strings:
		$string_1 = {
			00 00
			00 00
			6C
			10 00
			00 00
			10 00
			00 00
			40
			00 00
			00 00
			40
			00 00
			10 00
			00 00
			10 00
			00 04 00
		}
	
	condition:
		any of them
	
}
