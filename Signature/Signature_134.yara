rule signature_134
{
	meta:
		author = "0xlsd"
		sample = "76c410a5be230018cd5993c68afc73c3e2dbb2fc9f244992fdfa90248d89d5b8"
	
	
	strings:
		$string_1 = {
			37
			2A D6
			10 25 ?? ?? ?? ??
			2A 52 ??
			63 68 ??
			30 37
			2A 00
			00 00
			00 00
			00 00
			00 50 ??
			00 00
			4C
			01 04 00
			A7
			87 3E
			50
			00 00
		}
	
	condition:
		any of them
	
}
