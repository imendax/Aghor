rule signature_129
{
	meta:
		author = "0xlsd"
		sample = "83c80d5d0c229fe012b72422b7e683683b4489827d550d6204e16d3102078dc4"
	
	
	strings:
		$string_1 = {
			07
			95
			44
		}
	
	condition:
		any of them
	
}
