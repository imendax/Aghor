rule signature_39
{
	meta:
		author = "0xlsd"
		sample = "3c5abbc1606b341400c23f3344f0505ae1bff48d0ce606165fc933d02089aa0c"
	
	
	strings:
		$string_1 = {
			98
			15 1C 80 0E D2
			0A 4F ??
			43
			61
		}
	
	condition:
		any of them
	
}
