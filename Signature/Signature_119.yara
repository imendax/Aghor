rule signature_119
{
	meta:
		author = "0xlsd"
		sample = "3b932d8db20987b568657e30a03732ac5ac0ad3eb0a2ded5c2f9d6b5a6adfa37"
	
	
	strings:
		$string_1 = {
			69 88 ?? ?? ?? ?? F3 73 69 88
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			50
			45
			00 00
			4C
		}
	
	condition:
		any of them
	
}
