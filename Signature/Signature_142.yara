rule signature_142
{
	meta:
		author = "0xlsd"
		sample = "c14cc759fe34d8386a95178c83790c0087877ebd9a369869dc6d61d084c71753"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 02
			32 00
			02 04 00
			00 0E
			00 00
			00 00
			00 00
			10 12
			00 00
			00 10
			00 00
			00 20
			04 00
			00 00
			40
			00 00
			10 00
			00 00
		}
	
	condition:
		any of them
	
}
