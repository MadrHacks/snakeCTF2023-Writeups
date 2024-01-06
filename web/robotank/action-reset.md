### Action Reset

By looking at the views we can see there's an admin page:

```
extends layout

block content
  div(class="admin-item-panel")
    each item in items
      .item-view 
        p= item.name
        p Owner: #{item.username}
        button(onclick=`resetOwnership(${item.id})`) Reset
  
  script(src="/js/admin.js")
```

The `resetOwnership` function is defined in the `admin.js` file:

```
const resetOwnership = (action_id) => {
  $.ajax({
    type: "POST",
    url: "/admin",
    contentType: "application/json",
    data: JSON.stringify({
      id: action_id,
    }),
    success: (data) => {
      // Handle the response from the server
      if (data.redirect) window.location.pathname = data.redirect;
      if (data.message) window.messagebox.innerText = data.message;
    },
    error: (error) => {
      console.error("Error:", error);
    },
  });
};
```

The code to reset the owner is protected by the `requireAdmin` middleware:
```
requireAdmin: (req, res, next) => {
  if (req.session.user.username === process.env.ADMIN_USERNAME) {
    return next();
  } else {
    res.redirect("/");
  }
}
....
router.post("/", body("id").notEmpty(), (req, res) => {
  const data = validate(req, res);
  if (!data) {
    return;
  }

  action_id = parseInt(data.id);
  if (isNaN(action_id)) {
    res.json({
      result: "failure",
    });
    return;
  }
  db.resetItemOwner(action_id).then((success) => {
    if (success) {
      res.json({
        result: "success",
        redirect: "/admin",
      });
    } else {
      res.json({
        result: "failure",
        redirect: "/admin",
      });
    }
  });
});
```

We notice that the application runs a bot which logs in and check the reports.
The code of the bot is available at `/src/utils/report.js`, it basically log in and visit the URL.

We can report via the endpoint `/report` (POST) or in the error page, and the admin will visit our url (if it is in the web page, checked via `BOT_SANITY_REGEX`).

This means that only the admin can reset the owner of an action and it must be in the website. How can we perform an XSS?

By checking our account page we notice that we can set a [motto](https://en.wikipedia.org/wiki/Motto) for the team, and it supports a little of [bbcode](https://en.wikipedia.org/wiki/BBCode).
The parser is in the file `bbrender.js`:

```
$(document).ready(() => {
  if (window.current_motto) {
    var current_motto = window.current_motto.innerText;
    if (current_motto.includes("<") || current_motto.includes(">")) return; // Welcome back to my laboratory, where safety is number one priority
    current_motto = current_motto.replace(/\[b\]/, "<strong>");
    current_motto = current_motto.replace(/\[\/b\]/, "</strong>");
    current_motto = current_motto.replace(/\[i\]/, "<i>");
    current_motto = current_motto.replace(/\[\/i\]/, "</i>");
    current_motto = current_motto.replace(/\[url ([^\]\ ]*)\]/, "<a href=$1>");
    current_motto = current_motto.replace(/(.*)\[\/url\]/, "$1</a>");
    // Images are so dangerous
    // current_motto = current_motto.replace(/\[img\]/, '<img src="');
    // current_motto = current_motto.replace(/\[\/img\]/, '" />');
    window.current_motto.innerHTML = current_motto;
  }
});
```

We notice that images tag are not parsed, but URLs are! We can focus on the line `current_motto = current_motto.replace(/\[url ([^\]\ ]*)\]/, "<a href=$1>")`: this regex is way too permissive, since the only constraint we have is that there's no `]` or whitespace in our payload!

In fact, we can insert the double quote to close the `href` attribute of the link and execute javascript with events like `onfocus`, triggered via `autofocus`.
With this XSS we can reset an action owner!

An example payload can be `[url ""onfocus="fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:1})})"autofocus]` to reset the action with ID 1.
