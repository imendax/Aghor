rule signature_132
{
	meta:
		author = "0xlsd"
		sample = "06b553969da1ab2dcf03fd2b7a02b684b03894915cf4db8af898b0ce0a7d17f1"
	
	
	strings:
		$string_1 = {
			22 CE
			7F ??
			BC CE 6C 89 22
			CE
			6D
			F1
			B1 CE
			77 ??
			22 CE
			64 89 23
			CE
			E7 89
			22 CE
			7F ??
			88 CE
			5D
			89 22
			CE
			7F ??
		}
	
	condition:
		any of them
	
}
