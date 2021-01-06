rule signature_147
{
	meta:
		author = "0xlsd"
		sample = "740aaa3ee5d7995386f6f00bdd0a85c372c238702229da2d8f3d75c37e0b856f"
	
	
	strings:
		$string_1 = {
			3F
			88 48 ??
			E0 D2
			F3 45
			98
			7D ??
			2E CB
			41
			DD 1E
			4A
			7D ??
			7B ??
			D5 1B
			70 ??
			FA
			FD
			9E
			56
			C1 E3 00
			66 99
			14 04
			D8 18
		}
	
	condition:
		any of them
	
}
