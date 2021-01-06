rule signature_121
{
	meta:
		author = "0xlsd"
		sample = "4e9670606d3fcb7e897ac13e3aee28aabf7e6768a4b59580390c7be099428edd"
	
	
	strings:
		$string_1 = {
			ED
			74 ??
			B7 96
			74 ??
			71 ??
			74 ??
			71 ??
			74 ??
			71 ??
			74 ??
			23 6E ??
			38 71 ??
			74 ??
			71 ??
			74 ??
			71 ??
			74 ??
			23 79 ??
		}
	
	condition:
		any of them
	
}
