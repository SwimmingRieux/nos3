package middleware

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nos3/internal/presentation"

	"github.com/labstack/echo/v4"
	"github.com/nbd-wtf/go-nostr"
)

func AuthMiddleware(action string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			authHeader := ctx.Request().Header.Get(presentation.AuthKey)
			if err := validateAuthHeader(authHeader); err != nil {
				ctx.Response().Header().Set(presentation.ReasonTag, err.Error())

				return ctx.NoContent(http.StatusUnauthorized)
			}

			event, err := decodeEvent(authHeader)
			if err != nil {
				ctx.Response().Header().Set(presentation.ReasonTag, err.Error())

				return ctx.NoContent(http.StatusUnauthorized)
			}

			if err := validateEvent(event, action); err != nil {
				ctx.Response().Header().Set(presentation.ReasonTag, err.Error())

				return ctx.NoContent(http.StatusUnauthorized)
			}

			ctx.Set(presentation.PK, event.PubKey)
			ctx.Set(presentation.XTag, getTagValue(event, presentation.XTag))
			ctx.Set(presentation.TTag, getTagValue(event, presentation.TTag))
			ctx.Set(presentation.ExpTag, getExpirationTime(event))

			return next(ctx)
		}
	}
}

func validateAuthHeader(authHeader string) error {
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Nostr ") {
		return fmt.Errorf("missing Nostr header prefix")
	}

	return nil
}

func decodeEvent(authHeader string) (*nostr.Event, error) {
	eventBase64 := strings.TrimPrefix(authHeader, "Nostr ")
	eventBytes, err := base64.StdEncoding.DecodeString(eventBase64)
	if err != nil {
		return nil, fmt.Errorf("decode base64 event failed: %s", err.Error())
	}

	event := &nostr.Event{}
	if err = json.Unmarshal(eventBytes, event); err != nil {
		return nil, fmt.Errorf("json decode failed: %s", err.Error())
	}

	return event, nil
}

func validateEvent(event *nostr.Event, action string) error {
	if ok, err := event.CheckSignature(); !ok || err != nil {
		return fmt.Errorf("invalid signature")
	}
	if event.Kind != 24242 {
		return fmt.Errorf("invalid kind")
	}
	if event.CreatedAt.Time().Unix() > time.Now().Add(1*time.Minute).Unix() {
		return fmt.Errorf("invalid created_at")
	}

	expiration := getTagValue(event, presentation.ExpTag)
	if expiration == "" {
		return fmt.Errorf("empty expiration tag")
	}

	t := getTagValue(event, presentation.TTag)
	if t == "" {
		return fmt.Errorf("empty t tag")
	}
	if t != action {
		return fmt.Errorf("invalid action")
	}

	expirationTime, err := strconv.Atoi(expiration)
	if err != nil || time.Unix(int64(expirationTime), 0).Unix() < time.Now().Unix() {
		return fmt.Errorf("invalid expiration")
	}

	return nil
}

func getTagValue(event *nostr.Event, tagName string) string {
	tag := event.Tags.Find(tagName)
	if len(tag) > 1 {
		return tag[1]
	}

	return ""
}

func getExpirationTime(event *nostr.Event) int {
	expiration := getTagValue(event, presentation.ExpTag)
	expirationTime, _ := strconv.Atoi(expiration)

	return expirationTime
}
