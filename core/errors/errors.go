package errors

import "fmt"

const (
	MissingFieldFormat = "missing required field: %s"
	MissingFieldCode   = 1001

	StorageErrorCode         = 2001
	StorageEntryNotFoundCode = 2002
)

type Error struct {
	Message string
	Code    uint64
}

func (e *Error) GetCode() uint64 {
	return e.Code
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

func MissingFieldError(fieldName string) *Error {
	return &Error{fmt.Sprintf(MissingFieldFormat, fieldName), MissingFieldCode}
}

func StorageError(message string) *Error {
	return &Error{message, StorageErrorCode}
}

func EntryNotFoundError(message string) *Error {
	return &Error{message, StorageEntryNotFoundCode}
}
