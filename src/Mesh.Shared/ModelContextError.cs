using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mesh.Shared;

public static class ModelContextError
{
    public static bool IsConfirmed(HttpStatusCode status, string body)
    {
        if (status is not (HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity)) return false;
        try
        {
            using var document = JsonDocument.Parse(body);
            var error = document.RootElement;
            if (error.ValueKind != JsonValueKind.Object) return false;
            if (error.TryGetProperty("error", out var nested)) error = nested;
            if (error.ValueKind != JsonValueKind.Object) return false;
            string Text(string key) => error.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString()! : "";
            if (Text("code") is "context_length_exceeded" or "context_window_exceeded" or "input_token_limit_exceeded") return true;
            if (Text("type") is "context_length_exceeded" or "context_window_exceeded") return true;
            var type = Text("type");
            var message = Text("message");
            return (type == "invalid_request_error" && Regex.IsMatch(message,
                    @"^prompt is too long: \d+ tokens > \d+ maximum", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                || (Text("status") == "INVALID_ARGUMENT" && Regex.IsMatch(message,
                    @"^The input token count \(\d+\) exceeds the maximum number of tokens allowed \(\d+\)", RegexOptions.CultureInvariant));
        }
        catch (JsonException) { return false; }
    }
}
