package store

import "time"

// The operations below change existing secrets. The daemon API does not offer
// them: only root (through `sudo secret ...`) can open the store file.

// Rotate replaces the value of an existing secret.
func (s *Store) Rotate(project, name, value string, now time.Time) error {
	return s.Update(func(m map[string]*Secret) error {
		sec, ok := m[project+"/"+name]
		if !ok {
			return ErrNotFound
		}
		c := *sec
		c.Value, c.UpdatedAt = value, now
		if err := c.Validate(); err != nil {
			return err
		}
		m[c.Key()] = &c
		return nil
	})
}

// Rebind changes the tier, kind and binding of an existing secret.
func (s *Store) Rebind(project, name string, tier Tier, kind Kind, b *Binding, now time.Time) error {
	return s.Update(func(m map[string]*Secret) error {
		sec, ok := m[project+"/"+name]
		if !ok {
			return ErrNotFound
		}
		c := *sec
		c.Tier, c.Kind, c.Binding, c.UpdatedAt = tier, kind, b, now
		if err := c.Validate(); err != nil {
			return err
		}
		m[c.Key()] = &c
		return nil
	})
}

// SetDefault makes a user-scope secret a default for all projects, or not.
func (s *Store) SetDefault(project, name string, def bool, now time.Time) error {
	return s.Update(func(m map[string]*Secret) error {
		sec, ok := m[project+"/"+name]
		if !ok {
			return ErrNotFound
		}
		c := *sec
		c.Default, c.UpdatedAt = def, now
		if err := c.Validate(); err != nil {
			return err
		}
		m[c.Key()] = &c
		return nil
	})
}

// Delete removes a secret.
func (s *Store) Delete(project, name string) error {
	return s.Update(func(m map[string]*Secret) error {
		if _, ok := m[project+"/"+name]; !ok {
			return ErrNotFound
		}
		delete(m, project+"/"+name)
		return nil
	})
}
