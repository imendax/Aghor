rule signature_1
{
	meta:
		author = "0xlsd"
		sample = "dcca25713e169b09b4ef0c4dac185678ce1cd680b8d0f79fbc54050070565b7f"
	
	
	strings:
		$string_1 = {
			54
			68 69 73 20 70
			72 ??
			67 72 ??
			6D
			20 6D ??
			73 ??
			20 62 ??
		
		}
			
	condition:
		any of them
	
}
