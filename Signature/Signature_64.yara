rule signature_64
{
	meta:
		author = "0xlsd"
		sample = "d85ed092738e1af5680978f3df359e08dceeb9ad179ae4ecc7ef1ab374532401"
	
	
	strings:
		$string_1 = {
			69 18 64 48 CB 3B
			30 31
			B4 87
			66 39 7E ??
			BE 47 D4 E8 7D
			B3 D1
			EC
			96
			D4 91
			F9
			CE
			39 97 ?? ?? ?? ??
			4A
			1B A7 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
