rule signature_53
{
	meta:
		author = "0xlsd"
		sample = "c8e7b7572ddd987ab48ab01e551d8ce8156016a607504da5cc13595108116a5e"
	
	
	strings:
		$string_1 = {
			40
			A6
			93
			1F
			D3 A6 ?? ?? ?? ??
			81 FA EF A6 95 67
			40
			A6
			81 FA DB A6 9B 67
			40
			A6
			81 FA DA A6 9B 67
			40
			A6
			81 FA DD A6 9B 67
		}
	
	condition:
		any of them
	
}
