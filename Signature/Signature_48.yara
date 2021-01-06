rule signature_48
{
	meta:
		author = "0xlsd"
		sample = "b06957b23d42ecec8b474264ff206dd2db900c3c2f4187d9d1d86b3b4329cb52"
	
	
	strings:
		$string_1 = {
			1F
			E7 F0
			68 64 E7 DE AE
			1F
			E7 D7
			AE
			1E
			E7 E8
			AE
			1F
			E7 C9
			FC
			9C
			E7 D6
			AE
			1F
			E7 D7
			AE
			1F
			E7 D6
			AE
			1F
			E7 C9
			FC
			8B E7
			D6
			AE
		}
	
	condition:
		any of them
	
}
