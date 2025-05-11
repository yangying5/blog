import json

target_num = 0xa8d44208
with open("1.json", "r", encoding="utf-8") as f:
    data = json.loads(f.read())
    segs = data.get("segments")
    for seg in segs:
        start = seg.get("start")
        end = seg.get("end")
        name = seg.get("name")
        content_file = seg.get("content_file")
        if start < target_num < end:
            print(name)
            print(start)
            print(end)
            print(content_file)