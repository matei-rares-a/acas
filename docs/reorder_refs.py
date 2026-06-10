import re

filepath = r"c:\local_store\files\my_workspace\acas\docs\Disertatie_Matei_Rares_5.md"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

bib_marker = "\nBibliografie\n"
bib_start_idx = content.find(bib_marker)
anexe_idx = content.find("\nAnexe\n", bib_start_idx)

if bib_start_idx == -1:
    raise SystemExit("ERROR: 'Bibliografie' section not found")
if anexe_idx == -1:
    raise SystemExit("ERROR: 'Anexe' section not found")

text_before_bib = content[:bib_start_idx]
bib_content = content[bib_start_idx + len(bib_marker):anexe_idx]
rest_after_bib = content[anexe_idx:]

# Find first-appearance order of [N] citations in the text body
order = []
for m in re.finditer(r"\[(\d+)\]", text_before_bib):
    num = int(m.group(1))
    if num not in order:
        order.append(num)

# mapping: old citation number -> new citation number (1-based, first-appearance order)
mapping = {old: new + 1 for new, old in enumerate(order)}

def apply_mapping(text, mapping):
    def replace(m):
        num = int(m.group(1))
        return "XREFX{}XREFX".format(mapping[num]) if num in mapping else m.group(0)
    result = re.sub(r"\[(\d+)\]", replace, text)
    return re.sub(r"XREFX(\d+)XREFX", lambda m: "[{}]".format(m.group(1)), result)

new_text_before_bib = apply_mapping(text_before_bib, mapping)

# Parse bibliography: tab-indented non-empty lines in order = entries [1], [2], ...
# (bibliography entries have no [N] prefix — they are positionally indexed)
entry_lines = [l for l in bib_content.split("\n") if l.startswith("\t") and l.strip()]
raw_entries = {i + 1: line for i, line in enumerate(entry_lines)}

print("Found {} bibliography entries".format(len(raw_entries)))
print("Found {} unique citations in text: {}".format(len(order), order))

# Build reordered entry list
new_entry_lines = []
for old_num in order:
    if old_num in raw_entries:
        new_entry_lines.append(raw_entries[old_num])
    else:
        print("WARNING: no bibliography entry for citation [{}]".format(old_num))

uncited = sorted(set(raw_entries.keys()) - set(order))
if uncited:
    print("WARNING: entries not cited in text, appended at end: {}".format(uncited))
    for old_num in uncited:
        new_entry_lines.append(raw_entries[old_num])

# Reconstruct bib section: replace entry lines in-place, keep all other lines (blank lines etc.)
def _update_bib_prefix(line: str, new_num: int) -> str:
    """If the entry line starts with \t[N] update N to new_num, otherwise leave as-is."""
    m = re.match(r'^(\t)\[(\d+)\](.*)', line, re.DOTALL)
    if m:
        return "{}[{}]{}".format(m.group(1), new_num, m.group(3))
    return line

entry_iter = iter(enumerate(new_entry_lines, start=1))
result_lines = []
for line in bib_content.split("\n"):
    if line.startswith("\t") and line.strip():
        new_num, new_line = next(entry_iter)
        result_lines.append(_update_bib_prefix(new_line, new_num))
    else:
        result_lines.append(line)

new_bib_content = "\n".join(result_lines)
new_content = new_text_before_bib + bib_marker + new_bib_content + rest_after_bib

with open(filepath, "w", encoding="utf-8") as f:
    f.write(new_content)

print("Done!")
print("Processed {} unique text citations, {} bib entries.".format(len(order), len(raw_entries)))
