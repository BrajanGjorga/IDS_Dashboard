# Server Alert View Changes

## Request

Update the **View alerts** page so it only presents alerts belonging to the selected server and displays that server's name in the page heading instead of **Network alerts**.

## Resulting behavior

Selecting **View alerts** for a server opens `/servers/{server_id}/alerts`. The route verifies that the selected server belongs to the signed-in user and redirects to the dashboard with the server filter in the query string:

```text
/?server_id={server_id}
```

The filtered dashboard now:

- lists only alerts whose `server_id` matches the selected server;
- displays the selected server's name as the main heading;
- calculates total, malicious, and last-24-hours counts for that server only;
- reports one monitored server while viewing a selected server;
- populates the prediction filter with predictions reported by that server only; and
- continues to return `404 Server not found` if a user requests a server they do not own.

The unfiltered dashboard keeps its existing **Network alerts** heading and account-wide information.

## Files changed

### `app/main.py`

The `dashboard` route now stores the result of `get_owned_server` in `selected_server`. This avoids performing an ownership check without retaining the server information needed by the template.

The SQLAlchemy condition previously named `owned_alerts` is now `visible_alerts`. It always enforces user ownership and adds `Alert.server_id == selected_server.id` when a server is selected. Summary and prediction queries use this condition.

The template context now includes `selected_server`.

No model classes or database schema were changed.

### `app/templates/dashboard.html`

The main `<h1>` displays `selected_server.server_name` for a server-filtered view. When no server is selected, it displays **Network alerts**. The supporting description also changes to explain the selected-server view.

### `tests/test_alerts.py`

`test_view_server_alerts_only_shows_that_servers_alerts` creates two servers with different alerts, follows **View alerts** for the first server, and verifies:

- the expected filtered redirect;
- the selected server name appears in the heading;
- the selected server's alert is visible;
- the other server's alert is absent; and
- the server-scoped summary count is shown.

## Existing methods involved

- `server_alerts`: validates server ownership and builds the filtered dashboard URL.
- `dashboard`: validates and loads the selected server, retrieves alerts, calculates summary values, and renders the page.
- `get_owned_server`: returns a server only when its ID and owning user both match.
- `list_alerts`: obtains the filtered alert records and count.
- `apply_alert_filters`: applies ownership and `server_id` constraints to the alert query.

## Verification

Run from the `alert-dashboard` directory:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
