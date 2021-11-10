{
    "plugin": {
        "pluginmetadataversion": 2,
        "name": "Blaze",
        "author": "Kudu Dynamics",
        "version": $version,
        "minimumbinaryninjaversion": 2660,
        "type": ["helper", "ui"],
        "api": ["python3"],
        "description": "Interact with interprocedural CFGs and simplified program models",
        "longdescription": "",
        "license": {
            "name": "Proprietary",
            "text": "Proprietary"
        },
        "platforms": [
            "Darwin",
            "Linux",
            "Windows"
        ],
        "installinstructions": {
            "Darwin": "",
            "Linux": "",
            "Windows": ""
        },
        "dependencies": $dependencies,
        "lastUpdated": $timestamp | tonumber,
        "projectUrl": "",
        "projectData": {
            "updated_at": $timestamp | tonumber | strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "authorUrl": "",
        "packageUrl": $packageurl,
        "path": "Kudu_Blaze",
    }
}
