from splunk_mcp_client import SplunkMCPClient

c = SplunkMCPClient.from_env()

# r = c.call_tool(
#     "saia_generate_spl",
#     {
#         "prompt": "Generate SPL for failed logins by user."
#     },
# )

# print("is_error=", r["is_error"])
# print(r["content"])
r = c.call_tool(
    "splunk_get_info",
    {
        "prompt": "Generate SPL for failed logins by user."
    },
)

print("is_error=", r["is_error"])
print(r["content"])
# from splunk_mcp_client import SplunkMCPClient

# c = SplunkMCPClient.from_env()

# for tool_name, args in [
#     (
#         "saia_ask_splunk_question",
#         {"prompt": "What does the stats command do in SPL?"},
#     ),
#     (
#         "saia_explain_spl",
#         {"spl": "index=main | stats count by host"},
#     ),
# ]:
#     r = c.call_tool(tool_name, args)
#     print("\nTOOL:", tool_name)
#     print("is_error=", r["is_error"])
#     print(r["content"])
# from splunk_mcp_client import SplunkMCPClient

# c = SplunkMCPClient.from_env()

# tools = c.list_tools()

# for t in tools:
#     print(t)