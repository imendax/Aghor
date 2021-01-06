rule signature_120
{
	meta:
		author = "0xlsd"
		sample = "725f8d01267a095621a7c704b56df5144f8c9bdfe486c6b156e7b2e7d6d858bc"
	
	
	strings:
		$string_1 = {
			0F 03 0B
			01 02
			02 00
			1C 00
			00 00
			5E
			00 00
			00 04 00
			00 40 ??
			00 00
			00 10
			00 00
			00 30
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
