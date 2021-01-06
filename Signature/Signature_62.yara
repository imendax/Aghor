rule signature_62
{
	meta:
		author = "0xlsd"
		sample = "5e4301d636892c4a1352bae77e30f0df64f814beded5dd65f948229581f2255a"
	
	
	strings:
		$string_1 = {
			CA 31 ED
			14 D6
			31 3C 37
			CA 31 37
			37
			CB
			31 7A ??
			CA 31 CD
			14 D3
			31 3E
			37
			CA 31 A0
			14 8F
			31 36
			37
			CA 31 ED
			14 D7
		}
	
	condition:
		any of them
	
}
