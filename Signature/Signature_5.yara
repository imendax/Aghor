rule signature_5
{
	meta:
		author = "0xlsd"
		sample = "23d648356c22f7596ae526e4531f2e325919116850cb609f989479c549b0f97a"
	
	
	strings:
		$string_1 = {
			B8 B7 B6 B5 B4
			B3 B2
			B1 B0
			AF
			AE
			AD
			AC
			AB
			AA
			A9 A8 A7 A6 A5
			A4
			A3 ?? ?? ?? ??
			9E
			9D
			9C
			9B
		}
	
	condition:
		any of them
	
}
