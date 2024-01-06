### Increase balance

The application presents a coupon, given to us at the login.

The coupon is generated at the register or reset of the account, and we consider it pretty safe since it is a `uuid-v4`. It allows us to redeem `5` unit of balance, which can be used to buy the actions that we want to execute.

The code that applies it is the following:

```
router.post(
  "/:id/coupon",
  body("coupon").notEmpty().isString(),
  async (req, res) => {
    const data = validate(req, res);
    if (!data) {
      return;
    }

    const accountID = parseInt(req.params.id);
    if (
      isNaN(accountID) ||
      +req.session.user.id !== accountID ||
      req.session.user.username === process.env.ADMIN_USERNAME
    ) {
      res.redirect(`/account/${req.session.user.id}`);
      return;
    }

    const requested_coupon = data.coupon;
    if (!isUuid(requested_coupon)) {
      res.status(403).json({
        result: "failure",
        message: "Invalid coupon",
      });
      return;
    }
    const { coupon } = await db.fetchUserById(req.session.user.id);
    try {
      if (requested_coupon === coupon) {
        await db.applyCoupon(req.session.user.id);
        res.json({
          result: "success",
          redirect: `/account/${req.session.user.id}`,
        });
        res.end();
        return;
      }
    } catch (error) {
      console.log(error);
    }
    res.status(403).json({
      result: "failure",
      message: "Invalid coupon",
    });
  }
);
```

We can see that the coupon is vulnerable to a vulnerability class called [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use), since the fetch, check and application are not made in a single transaction!

We can then use `grequests` to apply it multiple times.
