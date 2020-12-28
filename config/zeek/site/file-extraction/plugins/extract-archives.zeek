@load ../__load__.zeek

module FileExtraction;

const archive_types: set[string] = {
								"application/x-7z-compressed",
					   			"application/x-rar",
					   			"application/zip",
								"application/gzip",
								"application/x-iso9660-image",
								"application/x-arj"
								};

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( meta$mime_type in archive_types )
		break;
	}
