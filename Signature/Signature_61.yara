rule signature_61
{
	meta:
		author = "0xlsd"
		sample = "6caaf63fcd58987351c8dcd548d8cd44ed1af19be2f95450e8be59e3e925648a"
	
	
	strings:
		$string_1 = {
			19 9B ?? ?? ?? ??
			86 E5
			19 9B ?? ?? ?? ??
			B6 E5
			19 9B ?? ?? ?? ??
			B6 E5
			19 9B ?? ?? ?? ??
			B6 E5
			19 9B ?? ?? ?? ??
			B6 E5
		}
	
	condition:
		any of them
	
}
