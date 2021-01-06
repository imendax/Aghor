rule signature_79
{
	meta:
		author = "0xlsd"
		sample = "b83b9ce57923d7cca53334483212f450cc7c4a9da882fb430c6faf0ae088c312"
	
	
	strings:
		$string_1 = {
			1C FC
			65 73 ??
			6D
			DA 23
			D6
			42
			32 94 C4 ?? ?? ?? ??
			D1 0E
			5C
			07
			5B
			2C 2F
			CF
			EE
			11 93 ?? ?? ?? ??
			07
			E6 E5
		}
	
	condition:
		any of them
	
}
