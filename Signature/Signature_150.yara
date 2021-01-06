rule signature_150
{
	meta:
		author = "0xlsd"
		sample = "f51a92a204a38444eae2a50f3663530b665a828c6fcc20fdcb8433724c578709"
	
	
	strings:
		$string_1 = {
			0F 01 0B
			01 02
			32 00
			44
			00 00
			00 CC
			CC
			00 00
			00 00
			00 00
			10 00
			00 00
			10 00
			00 00
			60
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
