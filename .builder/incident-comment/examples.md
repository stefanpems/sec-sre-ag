## Examples

### Example 1: Post plain text

**User:** "Add this comment to incident 12345: The user confirmed this was an authorized test."

```
Step 1: KQL → SecurityIncident | where ProviderIncidentId == "12345" or IncidentNumber == 12345
   → Found: ProviderIncidentId=12345 (preferred match), IncidentName (GUID) = "abc-def-..."
Step 2: Content = "The user confirmed this was an authorized test." → save to tmp file
Step 3: python3 format_comment.py input.txt --output-json body.json
            --output-readable body_readable.txt --api sentinel
        → type=text, chars=49
Step 4: Get ARM token (RunAzCliReadCommands) → save to file → Python urllib PUT
Step 5: "Comment posted successfully on incident #12345."
```

### Example 2: Post Markdown investigation report

**User:** "Post the investigation report as a comment on the incident."

```
Step 1: Incident ID from conversation context (e.g., 98765)
        KQL → ProviderIncidentId == "98765" → GUID = "xyz-..."
Step 2: Content = previous investigation output (Markdown) → save to tmp file
Step 3: python3 format_comment.py report.md --output-json body.json
            --output-readable body_readable.txt --api sentinel
        → type=markdown, chars=4200 (converted to HTML)
Step 4: Get ARM token → save to file → Python urllib PUT with body from body.json
Step 5: "Comment posted on incident #98765. Content converted from Markdown to HTML."
```

### Example 3: Post HTML report

**User:** "Post the HTML report as a comment on incident 54321."

```
Step 1: KQL → ProviderIncidentId == "54321" → GUID = "pqr-..."
Step 2: Content = HTML report file → use file path directly
Step 3: python3 format_comment.py report.html --output-json body.json
            --output-readable body_readable.txt --api sentinel
        → type=html, chars=8500 (adapted for single column)
Step 4: Get ARM token → save to file → Python urllib PUT with body from body.json
Step 5: "Comment posted on incident #54321. HTML adapted for the single-column layout."
```